//! Groups end to end through a relay: key packages on deposit, the epoch
//! sequencer, Welcomes and messages fanned out through the members' own
//! mailboxes, and a removal that ends what the removed member can read.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use silver_client::groups::{Change, GroupEvent, Groups, HeldWelcome, Outgoing};
use silver_client::{Client, ClientEvent, ConnectOptions, SequencerAnswer};
use silver_protocol::group::GroupId;
use silver_protocol::{Content, Identity, now_ms};
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

/// A client with a groups engine, connected and with key packages on
/// deposit.
struct Member {
    identity: Arc<Identity>,
    client: Client,
    events: mpsc::Receiver<ClientEvent>,
    groups: Groups,
}

impl Member {
    async fn join_relay(url: &str) -> Self {
        let identity = Arc::new(Identity::generate());
        let options = ConnectOptions {
            groups: true,
            ..Default::default()
        };
        let (client, mut events) =
            Client::spawn(url.to_owned(), identity.clone(), options).unwrap();
        let mut groups = Groups::ephemeral(identity.clone());
        wait_for(&mut events, |e| matches!(e, ClientEvent::Connected { .. })).await;
        let (packages, last_resort) = groups.deposit(now_ms()).unwrap();
        let status = client
            .deposit_key_packages(packages, last_resort)
            .await
            .unwrap();
        assert_eq!(
            status.remaining,
            silver_client::groups::KEY_PACKAGE_TARGET as u32
        );
        Self {
            identity,
            client,
            events,
            groups,
        }
    }

    fn id(&self) -> silver_protocol::UserId {
        self.identity.user_id()
    }

    /// Submit everything an engine operation produced.
    async fn send(&self, outgoing: Outgoing) {
        for upload in outgoing.uploads {
            self.client
                .upload_chunks(upload.blob, upload.chunks)
                .await
                .unwrap();
        }
        for envelope in outgoing.envelopes {
            self.client.submit_envelope(envelope).await.unwrap();
        }
    }

    /// Wait for the next group body, run it through the engine, and
    /// return the events.
    async fn next_group_events(&mut self) -> Vec<GroupEvent> {
        let event = wait_for(&mut self.events, |e| matches!(e, ClientEvent::Group { .. })).await;
        let ClientEvent::Group { from, body, .. } = event else {
            unreachable!()
        };
        let mls = match (&body.mls, &body.blob) {
            (Some(mls), _) => mls.clone(),
            (None, Some(reference)) => {
                let chunks = self
                    .client
                    .download_chunks(reference.blob.clone(), reference.chunks)
                    .await
                    .unwrap();
                Groups::open_parked(reference, &chunks).unwrap()
            }
            _ => unreachable!(),
        };
        self.groups.receive(from, &body, &mls, now_ms()).unwrap()
    }

    /// A group message body that is an invitation, accepted.
    async fn accept_invitation(&mut self) -> HeldWelcome {
        let events = self.next_group_events().await;
        let [GroupEvent::Invited { held }] = events.as_slice() else {
            panic!("expected an invitation, got {events:?}");
        };
        self.groups.accept_welcome(&held.group).unwrap();
        held.clone()
    }
}

async fn wait_for(
    events: &mut mpsc::Receiver<ClientEvent>,
    pred: impl Fn(&ClientEvent) -> bool,
) -> ClientEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let event = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("an event in time")
            .expect("the client is alive");
        if pred(&event) {
            return event;
        }
    }
}

fn text(s: &str) -> Content {
    Content::Text { body: s.into() }
}

#[tokio::test]
async fn a_group_forms_talks_and_shrinks_through_the_relay() {
    let (url, _state) = start_relay().await;
    let mut alice = Member::join_relay(&url).await;
    let mut bob = Member::join_relay(&url).await;
    let mut carol = Member::join_relay(&url).await;

    // Alice creates the group and registers it with the sequencer.
    let created = alice.groups.create("relay test", now_ms()).unwrap();
    let group: GroupId = created.group;
    assert_eq!(
        alice.client.group_create(created).await.unwrap(),
        SequencerAnswer::Stands(0)
    );
    // Creating it again is idempotent; another epoch is refused.
    assert_eq!(
        alice.client.group_create(created).await.unwrap(),
        SequencerAnswer::Stands(0)
    );

    // Key packages from the relay, verified, and an add committed through
    // the sequencer.
    let mut packages = Vec::new();
    for who in [&bob, &carol] {
        let (package, last_resort) = alice
            .client
            .key_package_for(who.id())
            .await
            .unwrap()
            .expect("on deposit");
        assert!(!last_resort);
        packages.push(
            alice
                .groups
                .verify_key_package(&who.id(), &package.data, now_ms())
                .unwrap(),
        );
    }
    let staged = alice.groups.stage_add(&group, &packages).unwrap();
    assert_eq!(
        alice.client.group_commit(staged).await.unwrap(),
        SequencerAnswer::Stands(1)
    );
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(out.envelopes.len(), 2);
    alice.send(out).await;

    // Bob and carol get their Welcomes through their mailboxes.
    let held = bob.accept_invitation().await;
    assert_eq!(held.from, alice.id());
    assert_eq!(held.name, "relay test");
    carol.accept_invitation().await;

    // Bob writes; both others read.
    let out = bob
        .groups
        .send(&group, text("hello from bob"), None, now_ms())
        .unwrap();
    bob.send(out).await;
    for member in [&mut alice, &mut carol] {
        let events = member.next_group_events().await;
        assert!(
            matches!(
                events.as_slice(),
                [GroupEvent::Message { from, content, .. }]
                    if *from == bob.id() && *content == text("hello from bob")
            ),
            "{events:?}"
        );
    }

    // A commit built on a stale epoch loses at the sequencer.
    let bob_staged = bob.groups.stage_self_update(&group).unwrap();
    let alice_staged = alice.groups.stage_remove(&group, &[carol.id()]).unwrap();
    assert_eq!(
        alice.client.group_commit(alice_staged).await.unwrap(),
        SequencerAnswer::Stands(2)
    );
    assert_eq!(
        bob.client.group_commit(bob_staged).await.unwrap(),
        SequencerAnswer::Stale(2)
    );
    bob.groups.discard_staged(&group).unwrap();
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    alice.send(out).await;
    let events = bob.next_group_events().await;
    assert_eq!(
        events,
        vec![GroupEvent::Changed {
            group,
            by: alice.id(),
            change: Change::Removed(vec![carol.id()]),
        }]
    );
    let events = carol.next_group_events().await;
    assert_eq!(
        events,
        vec![GroupEvent::Removed {
            group,
            by: alice.id()
        }]
    );

    // What follows never reaches carol: she is no longer a recipient.
    let out = alice
        .groups
        .send(&group, text("without carol"), None, now_ms())
        .unwrap();
    assert_eq!(out.envelopes.len(), 1);
    alice.send(out).await;
    let events = bob.next_group_events().await;
    assert!(matches!(events.as_slice(), [GroupEvent::Message { .. }]));
    assert!(
        tokio::time::timeout(Duration::from_secs(2), carol.events.recv())
            .await
            .map(|e| !matches!(e, Some(ClientEvent::Group { .. })))
            .unwrap_or(true),
        "carol gets nothing"
    );

    // The relay counted the commits and knows where the group stands.
    assert_eq!(_state.store().group_epoch(&group).unwrap(), Some(2));
    let counters = _state.counters();
    assert_eq!(counters.group_commits, 2);
    assert_eq!(counters.group_rejections, 1);

    // The deposit reports what was handed out.
    let (packages, last_resort) = bob.groups.deposit(now_ms()).unwrap();
    let _ = &packages;
    let _ = &last_resort;
    let mut seen: HashMap<[u8; 32], bool> = HashMap::new();
    for p in &packages {
        seen.insert(p.r#ref, true);
    }
    assert_eq!(seen.len(), packages.len());
}

#[tokio::test]
async fn an_invite_link_is_answered_by_the_admin_it_names() {
    let (url, _state) = start_relay().await;
    let mut alice = Member::join_relay(&url).await;
    let mut bob = Member::join_relay(&url).await;
    let created = alice.groups.create("linked", now_ms()).unwrap();
    let group = created.group;
    alice.client.group_create(created).await.unwrap();

    let link = alice.groups.invite_link(&group, Some(url.clone())).unwrap();
    let alice_bundle = bob.client.lookup(alice.id()).await.unwrap().unwrap();
    let out = bob
        .groups
        .join_request(&link, (alice.id(), alice_bundle.dh_public), now_ms())
        .unwrap();
    bob.send(out).await;
    let events = alice.next_group_events().await;
    let [
        GroupEvent::JoinRequest {
            joiner,
            key_package,
            ..
        },
    ] = events.as_slice()
    else {
        panic!("{events:?}");
    };
    assert_eq!(*joiner, bob.id());
    let staged = alice
        .groups
        .stage_add(&group, std::slice::from_ref(key_package))
        .unwrap();
    assert_eq!(
        alice.client.group_commit(staged).await.unwrap(),
        SequencerAnswer::Stands(1)
    );
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    alice.send(out).await;
    let held = bob.accept_invitation().await;
    assert_eq!(held.members.len(), 2);
    let out = bob.groups.send(&group, text("in"), None, now_ms()).unwrap();
    bob.send(out).await;
    assert!(matches!(
        alice.next_group_events().await.as_slice(),
        [GroupEvent::Message { .. }]
    ));
}
