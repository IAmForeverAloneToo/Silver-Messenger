//! The engine, driven end to end between ephemeral engines with a fake
//! sequencer in place of the relay: nothing here touches the network.

use std::collections::HashMap;
use std::sync::Arc;

use silver_protocol::group::{GroupId, token_hash};
use silver_protocol::{Body, Content, Envelope, Identity, now_ms, open_bytes};

use super::*;

/// The relay's sequencer, in a map.
#[derive(Default)]
struct Sequencer {
    entries: HashMap<GroupId, (u64, [u8; 32])>,
}

impl Sequencer {
    fn create(&mut self, created: Created) {
        self.entries
            .entry(created.group)
            .or_insert((created.epoch, created.next));
    }

    /// `Ok(epoch)` as the relay would answer, `Err(where it stands)` for a
    /// stale or wrong commit.
    fn commit(&mut self, staged: Staged) -> std::result::Result<u64, u64> {
        let entry = self.entries.get_mut(&staged.group).expect("created");
        if entry.0 != staged.epoch || entry.1 != token_hash(&staged.token) {
            return Err(entry.0);
        }
        *entry = (staged.epoch + 1, staged.next);
        Ok(entry.0)
    }
}

struct Party {
    identity: Arc<Identity>,
    groups: Groups,
    inbox: Vec<Envelope>,
}

impl Party {
    fn new() -> Self {
        let identity = Arc::new(Identity::generate());
        Self {
            identity: identity.clone(),
            groups: Groups::ephemeral(identity),
            inbox: Vec::new(),
        }
    }

    /// A linked device of `account`'s: its own keys, certified by the
    /// account, and an engine that acts for the account.
    fn device_of(account: &Party, name: &str) -> Self {
        let identity = Arc::new(Identity::generate());
        let certificate = account
            .identity
            .certify_device(&identity.user_id(), name, now_ms())
            .unwrap();
        Self {
            identity: identity.clone(),
            groups: Groups::ephemeral_device(identity, certificate),
            inbox: Vec::new(),
        }
    }

    fn id(&self) -> UserId {
        self.identity.user_id()
    }

    /// A key package as the relay would hand it out.
    fn key_package(&mut self) -> Vec<u8> {
        let (packages, _) = self.groups.deposit(now_ms()).unwrap();
        packages[0].data.clone()
    }

    /// Open every envelope in the inbox and feed the engine; the events.
    fn drain(&mut self, blobs: &HashMap<String, Vec<Vec<u8>>>) -> Vec<GroupEvent> {
        let mut events = Vec::new();
        for envelope in std::mem::take(&mut self.inbox) {
            let opened = open_bytes(&self.identity, &envelope).unwrap();
            let Body::Group(body) = Body::decode(&opened.body).unwrap() else {
                panic!("not a group body");
            };
            let mls = match (&body.mls, &body.blob) {
                (Some(mls), _) => mls.clone(),
                (None, Some(reference)) => {
                    let chunks = blobs.get(&reference.blob).expect("uploaded");
                    Groups::open_parked(reference, chunks).unwrap()
                }
                _ => unreachable!(),
            };
            events.extend(
                self.groups
                    .receive(opened.from, &body, &mls, now_ms())
                    .unwrap(),
            );
        }
        events
    }
}

/// Deliver `outgoing` to the parties it addresses, and park its blobs.
fn deliver(
    outgoing: Outgoing,
    parties: &mut [&mut Party],
    blobs: &mut HashMap<String, Vec<Vec<u8>>>,
) {
    for upload in outgoing.uploads {
        blobs.insert(upload.blob, upload.chunks);
    }
    for envelope in outgoing.envelopes {
        let target = parties
            .iter_mut()
            .find(|p| p.id() == envelope.to)
            .expect("a known recipient");
        target.inbox.push(envelope);
    }
}

fn text(s: &str) -> Content {
    Content::Text { body: s.into() }
}

/// Alice creates a group and adds bob and carol; everyone is in sync.
fn three(
    seq: &mut Sequencer,
    blobs: &mut HashMap<String, Vec<Vec<u8>>>,
) -> (Party, Party, Party, GroupId) {
    let mut alice = Party::new();
    let mut bob = Party::new();
    let mut carol = Party::new();
    let created = alice.groups.create("the papers", now_ms()).unwrap();
    seq.create(created);
    let group = created.group;
    let bob_kp = alice
        .groups
        .verify_key_package(&bob.id(), &bob.key_package(), now_ms())
        .unwrap();
    let carol_kp = alice
        .groups
        .verify_key_package(&carol.id(), &carol.key_package(), now_ms())
        .unwrap();
    let staged = alice.groups.stage_add(&group, &[bob_kp, carol_kp]).unwrap();
    assert_eq!(staged.epoch, 0);
    assert_eq!(seq.commit(staged), Ok(1));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(
        out.envelopes.len(),
        2,
        "a Welcome each, no commit to nobody"
    );
    deliver(out, &mut [&mut bob, &mut carol], blobs);
    for party in [&mut bob, &mut carol] {
        let events = party.drain(blobs);
        let [GroupEvent::Invited { held }] = events.as_slice() else {
            panic!("expected an invitation, got {events:?}");
        };
        assert_eq!(held.from, alice.id());
        assert_eq!(held.name, "the papers");
        assert_eq!(held.members.len(), 3);
        assert_eq!(held.group, group);
        party.groups.accept_welcome(&group).unwrap();
    }
    (alice, bob, carol, group)
}

#[test]
fn a_group_is_created_joined_and_messaged() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    for party in [&alice, &bob, &carol] {
        let record = party.groups.get(&group).unwrap();
        assert_eq!(record.name, "the papers");
        assert_eq!(record.members.len(), 3);
        assert!(record.is_admin(&alice.id()));
        assert!(!record.is_admin(&bob.id()));
        assert_eq!(record.state, GroupState::Active);
    }
    // Bob writes; alice and carol read it, once.
    let out = bob
        .groups
        .send(&group, text("hello all"), None, now_ms())
        .unwrap();
    let id = out.id.clone().unwrap();
    assert_eq!(out.envelopes.len(), 2);
    assert!(out.uploads.is_empty(), "a text goes inline");
    let copy = Outgoing {
        id: out.id.clone(),
        envelopes: out.envelopes.clone(),
        uploads: Vec::new(),
    };
    deliver(out, &mut [&mut alice, &mut carol], &mut blobs);
    for party in [&mut alice, &mut carol] {
        let events = party.drain(&blobs);
        assert_eq!(
            events,
            vec![GroupEvent::Message {
                group,
                from: bob.id(),
                id: id.clone(),
                sent_at_ms: events
                    .iter()
                    .find_map(|e| match e {
                        GroupEvent::Message { sent_at_ms, .. } => Some(*sent_at_ms),
                        _ => None,
                    })
                    .unwrap(),
                content: text("hello all"),
            }]
        );
    }
    // Delivered twice: MLS refuses the replay (the front end drops
    // duplicate envelopes by id before they get here).
    deliver(copy, &mut [&mut alice, &mut carol], &mut blobs);
    assert!(matches!(
        alice.drain(&blobs).as_slice(),
        [GroupEvent::Refused { .. }]
    ));
    // Carol answers.
    let out = carol
        .groups
        .send(&group, text("hi bob"), None, now_ms())
        .unwrap();
    deliver(out, &mut [&mut alice, &mut bob], &mut blobs);
    assert!(matches!(
        bob.drain(&blobs).as_slice(),
        [GroupEvent::Message { from, .. }] if *from == carol.id()
    ));
}

#[test]
fn members_are_removed_and_leave_and_cannot_read_on() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    // Bob cannot remove anyone.
    assert!(matches!(
        bob.groups.stage_remove(&group, &[carol.id()]),
        Err(GroupError::NotAdmin)
    ));
    // Alice removes carol.
    let staged = alice.groups.stage_remove(&group, &[carol.id()]).unwrap();
    assert_eq!(seq.commit(staged), Ok(2));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(out.envelopes.len(), 2);
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    assert_eq!(
        bob.drain(&blobs),
        vec![GroupEvent::Changed {
            group,
            by: alice.id(),
            change: Change::Removed(vec![carol.id()]),
        }]
    );
    assert_eq!(
        carol.drain(&blobs),
        vec![GroupEvent::Removed {
            group,
            by: alice.id()
        }]
    );
    assert_eq!(
        carol.groups.get(&group).unwrap().state,
        GroupState::Removed { by: alice.id() }
    );
    assert!(
        carol
            .groups
            .send(&group, text("x"), None, now_ms())
            .is_err()
    );
    // What alice sends now, carol cannot read (she gets nothing at all:
    // she is not a member the sender knows of).
    let out = alice
        .groups
        .send(&group, text("after"), None, now_ms())
        .unwrap();
    assert_eq!(out.envelopes.len(), 1);
    assert_eq!(out.envelopes[0].to, bob.id());
    deliver(out, &mut [&mut bob], &mut blobs);
    assert_eq!(bob.drain(&blobs).len(), 1);
    // Bob leaves: a proposal to alice, who commits it.
    let out = bob.groups.leave(&group).unwrap();
    assert_eq!(bob.groups.get(&group).unwrap().state, GroupState::Left);
    deliver(out, &mut [&mut alice], &mut blobs);
    assert_eq!(
        alice.drain(&blobs),
        vec![GroupEvent::LeaveProposed {
            group,
            member: bob.id()
        }]
    );
    let staged = alice.groups.stage_self_update(&group).unwrap();
    assert_eq!(seq.commit(staged), Ok(3));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(
        out.envelopes.len(),
        1,
        "the commit still reaches the leaver"
    );
    assert_eq!(alice.groups.get(&group).unwrap().members.len(), 1);
    deliver(out, &mut [&mut bob], &mut blobs);
    assert!(
        bob.drain(&blobs).is_empty(),
        "the commit reaches a group he left, and says nothing"
    );
    // The last admin cannot leave a group with members; alone, she can.
    assert!(alice.groups.leave(&group).is_ok());
    assert!(alice.groups.forget(&group).is_ok());
    assert!(alice.groups.get(&group).is_none());
}

#[test]
fn admins_are_appointed_names_change_and_links_rotate() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    assert!(matches!(
        bob.groups.invite_link(&group, None),
        Err(GroupError::NotAdmin)
    ));
    let link = alice
        .groups
        .invite_link(&group, Some("wss://r/ws".into()))
        .unwrap();
    assert_eq!(link.via, alice.id());

    let staged = alice.groups.stage_admin(&group, bob.id(), true).unwrap();
    assert_eq!(seq.commit(staged), Ok(2));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    let events = bob.drain(&blobs);
    assert!(
        matches!(
            events.as_slice(),
            [GroupEvent::Changed { change: Change::Admins(admins), .. }] if admins.contains(&bob.id())
        ),
        "{events:?}"
    );
    carol.drain(&blobs);
    assert!(bob.groups.get(&group).unwrap().is_admin(&bob.id()));
    let bob_link = bob.groups.invite_link(&group, None).unwrap();
    assert_eq!(bob_link.key, link.key, "the same invite key, another admin");

    // Bob renames; carol sees the name.
    let staged = bob
        .groups
        .stage_rename(&group, "the papers, vol. 2")
        .unwrap();
    assert_eq!(seq.commit(staged), Ok(3));
    let out = bob.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut alice, &mut carol], &mut blobs);
    alice.drain(&blobs);
    assert_eq!(
        carol.drain(&blobs),
        vec![GroupEvent::Changed {
            group,
            by: bob.id(),
            change: Change::Renamed("the papers, vol. 2".into())
        }]
    );
    assert_eq!(carol.groups.get(&group).unwrap().name, "the papers, vol. 2");

    // A link reset voids the old link.
    let staged = alice.groups.stage_link_reset(&group).unwrap();
    assert_eq!(seq.commit(staged), Ok(4));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    assert_eq!(
        bob.drain(&blobs),
        vec![GroupEvent::Changed {
            group,
            by: alice.id(),
            change: Change::LinkReset
        }]
    );
    carol.drain(&blobs);
    assert_ne!(
        alice.groups.invite_link(&group, None).unwrap().key,
        link.key
    );

    // The last admin cannot be demoted.
    let staged = alice.groups.stage_admin(&group, bob.id(), false).unwrap();
    assert_eq!(seq.commit(staged), Ok(5));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    bob.drain(&blobs);
    carol.drain(&blobs);
    assert!(matches!(
        alice.groups.stage_admin(&group, alice.id(), false),
        Err(GroupError::LastAdmin)
    ));
}

#[test]
fn a_link_lets_a_stranger_ask_and_an_admin_add_them() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    let mut dave = Party::new();
    let link = alice.groups.invite_link(&group, None).unwrap();
    let out = dave
        .groups
        .join_request(&link, (alice.id(), alice.identity.dh_public()), now_ms())
        .unwrap();
    deliver(out, &mut [&mut alice], &mut blobs);
    let events = alice.drain(&blobs);
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
    assert_eq!(*joiner, dave.id());
    let staged = alice
        .groups
        .stage_add(&group, std::slice::from_ref(key_package))
        .unwrap();
    assert_eq!(seq.commit(staged), Ok(2));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(
        out.envelopes.len(),
        3,
        "the commit to two, the Welcome to one"
    );
    deliver(out, &mut [&mut bob, &mut carol, &mut dave], &mut blobs);
    bob.drain(&blobs);
    carol.drain(&blobs);
    // Dave asked this admin: her Welcome is taken without a second yes.
    assert_eq!(dave.drain(&blobs), vec![GroupEvent::Joined { group }]);
    let record = dave.groups.get(&group).unwrap();
    assert_eq!(record.state, GroupState::Active);
    assert_eq!(record.members.len(), 4);
    // Dave reads what comes next.
    let out = bob
        .groups
        .send(&group, text("welcome dave"), None, now_ms())
        .unwrap();
    deliver(out, &mut [&mut alice, &mut carol, &mut dave], &mut blobs);
    assert!(matches!(
        dave.drain(&blobs).as_slice(),
        [GroupEvent::Message { .. }]
    ));
    alice.drain(&blobs);
    carol.drain(&blobs);

    // A stale link (after a reset) is refused; a proof for another group too.
    let staged = alice.groups.stage_link_reset(&group).unwrap();
    assert_eq!(seq.commit(staged), Ok(3));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol, &mut dave], &mut blobs);
    let mut eve = Party::new();
    let out = eve
        .groups
        .join_request(&link, (alice.id(), alice.identity.dh_public()), now_ms())
        .unwrap();
    deliver(out, &mut [&mut alice], &mut blobs);
    let events = alice.drain(&blobs);
    assert!(
        matches!(events.as_slice(), [GroupEvent::Refused { .. }]),
        "{events:?}"
    );
}

#[test]
fn the_loser_of_a_commit_race_discards_and_follows_the_winner() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    // Bob and alice both build a commit on epoch 1; alice's reaches the
    // sequencer first.
    let bob_staged = bob.groups.stage_self_update(&group).unwrap();
    let alice_staged = alice.groups.stage_rename(&group, "renamed").unwrap();
    assert_eq!(seq.commit(alice_staged), Ok(2));
    assert_eq!(seq.commit(bob_staged), Err(2));
    bob.groups.discard_staged(&group).unwrap();
    assert!(!bob.groups.has_staged(&group));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    assert!(matches!(
        bob.drain(&blobs).as_slice(),
        [GroupEvent::Changed {
            change: Change::Renamed(_),
            ..
        }]
    ));
    carol.drain(&blobs);
    // Bob tries again on the new epoch and wins.
    let staged = bob.groups.stage_self_update(&group).unwrap();
    assert_eq!(staged.epoch, 2);
    assert_eq!(seq.commit(staged), Ok(3));
    let out = bob.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut alice, &mut carol], &mut blobs);
    assert_eq!(
        alice.drain(&blobs),
        vec![GroupEvent::Changed {
            group,
            by: bob.id(),
            change: Change::Updated
        }]
    );
    // A member whose own staged commit is overtaken while it waits has it
    // cleared when the winner arrives.
    let _pending = carol.groups.stage_self_update(&group).unwrap();
    let staged = alice.groups.stage_self_update(&group).unwrap();
    assert_eq!(seq.commit(staged), Ok(4));
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    bob.drain(&blobs);
    carol.drain(&blobs);
    assert!(!carol.groups.has_staged(&group));
    assert_eq!(carol.groups.get(&group).unwrap().members.len(), 3);
    // Tokens of past epochs are kept for a rewound relay.
    let steps = alice.groups.catch_up(&group, 1).unwrap();
    assert_eq!(
        steps.iter().map(|s| s.epoch).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    let entry = alice.groups.sequencer_entry(&group).unwrap();
    assert_eq!(entry.epoch, 4);
}

#[test]
fn a_commit_that_breaks_the_rules_breaks_the_group_for_everyone_honest() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    // Bob, no admin, forges an add by running the engine past its checks:
    // his engine refuses, so drive OpenMLS directly.
    let mut mallory = Party::new();
    let kp = parse_key_package(&mallory.key_package(), bob.groups.provider.crypto()).unwrap();
    let Groups {
        handles,
        provider,
        signer,
        ..
    } = &mut bob.groups;
    let handle = load_handle(handles, provider, &group).unwrap();
    let bundle = handle
        .commit_builder()
        .propose_adds([kp])
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &*signer, |_| true)
        .unwrap()
        .stage_commit(&*provider)
        .unwrap();
    let (commit, _, _) = bundle.into_messages();
    let commit = commit.tls_serialize_detached().unwrap();
    let recipients: Vec<MemberInfo> = bob
        .groups
        .get(&group)
        .unwrap()
        .members
        .iter()
        .filter(|m| m.user != bob.id())
        .cloned()
        .collect();
    let (body, _) = bob
        .groups
        .frame(&group, GroupKind::Handshake, commit)
        .unwrap();
    let envelopes = bob.groups.seal_to(&recipients, &body).unwrap();
    deliver(
        Outgoing {
            id: None,
            envelopes,
            uploads: Vec::new(),
        },
        &mut [&mut alice, &mut carol],
        &mut blobs,
    );
    for party in [&mut alice, &mut carol] {
        let events = party.drain(&blobs);
        assert!(
            matches!(
                events.as_slice(),
                [GroupEvent::Broken { by, .. }] if *by == bob.id()
            ),
            "{events:?}"
        );
        assert!(matches!(
            party.groups.get(&group).unwrap().state,
            GroupState::Broken { .. }
        ));
        assert!(
            party
                .groups
                .send(&group, text("x"), None, now_ms())
                .is_err()
        );
    }
}

#[test]
fn commits_that_cross_on_the_wire_are_held_and_applied_in_order() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    // Two commits in a row from alice; carol gets the second first.
    let staged = alice.groups.stage_rename(&group, "one").unwrap();
    seq.commit(staged).unwrap();
    let first = alice.groups.commit_staged(&group, now_ms()).unwrap();
    let staged = alice.groups.stage_rename(&group, "two").unwrap();
    seq.commit(staged).unwrap();
    let second = alice.groups.commit_staged(&group, now_ms()).unwrap();
    let (carol_id, bob_id) = (carol.id(), bob.id());
    let to_carol = move |out: &Outgoing| Outgoing {
        id: None,
        envelopes: out
            .envelopes
            .iter()
            .filter(|e| e.to == carol_id)
            .cloned()
            .collect(),
        uploads: Vec::new(),
    };
    let to_bob = move |out: &Outgoing| Outgoing {
        id: None,
        envelopes: out
            .envelopes
            .iter()
            .filter(|e| e.to == bob_id)
            .cloned()
            .collect(),
        uploads: Vec::new(),
    };
    deliver(to_carol(&second), &mut [&mut carol], &mut blobs);
    assert!(carol.drain(&blobs).is_empty(), "held for the epoch between");
    assert_eq!(carol.groups.get(&group).unwrap().name, "the papers");
    deliver(to_carol(&first), &mut [&mut carol], &mut blobs);
    let events = carol.drain(&blobs);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(carol.groups.get(&group).unwrap().name, "two");
    deliver(to_bob(&first), &mut [&mut bob], &mut blobs);
    deliver(to_bob(&second), &mut [&mut bob], &mut blobs);
    assert_eq!(bob.drain(&blobs).len(), 2);
    assert_eq!(bob.groups.get(&group).unwrap().name, "two");
    // Messages sent in the epoch before a commit still decrypt after it.
    let staged = alice.groups.stage_rename(&group, "three").unwrap();
    let late = bob
        .groups
        .send(&group, text("late"), None, now_ms())
        .unwrap();
    seq.commit(staged).unwrap();
    let commit = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(to_carol(&commit), &mut [&mut carol], &mut blobs);
    carol.drain(&blobs);
    deliver(to_carol(&late), &mut [&mut carol], &mut blobs);
    assert!(matches!(
        carol.drain(&blobs).as_slice(),
        [GroupEvent::Message { .. }]
    ));
}

#[test]
fn a_member_out_of_sync_is_removed_and_added_back() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut carol, group) = three(&mut seq, &mut blobs);
    // Carol misses many commits.
    for i in 0..(HOLD_LIMIT + 1) {
        let staged = alice.groups.stage_rename(&group, &format!("n{i}")).unwrap();
        seq.commit(staged).unwrap();
        let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
        deliver(
            Outgoing {
                id: None,
                envelopes: out
                    .envelopes
                    .iter()
                    .filter(|e| e.to == bob.id())
                    .cloned()
                    .collect(),
                uploads: Vec::new(),
            },
            &mut [&mut bob],
            &mut blobs,
        );
        bob.drain(&blobs);
    }
    let out = alice
        .groups
        .send(&group, text("now"), None, now_ms())
        .unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    assert!(matches!(
        carol.drain(&blobs).as_slice(),
        [GroupEvent::Refused { .. }]
    ));
    // The next commit she sees is far ahead: out of sync.
    let staged = alice.groups.stage_rename(&group, "far").unwrap();
    seq.commit(staged).unwrap();
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    bob.drain(&blobs);
    assert_eq!(carol.drain(&blobs), vec![GroupEvent::OutOfSync { group }]);
    let out = carol.groups.rejoin_request(&group, now_ms()).unwrap();
    assert_eq!(out.envelopes.len(), 1, "to the one admin");
    deliver(out, &mut [&mut alice], &mut blobs);
    let events = alice.drain(&blobs);
    let [
        GroupEvent::RejoinRequest {
            member,
            key_package,
            ..
        },
    ] = events.as_slice()
    else {
        panic!("{events:?}");
    };
    assert_eq!(*member, carol.id());
    let staged = alice
        .groups
        .stage_rejoin(&group, carol.id(), key_package)
        .unwrap();
    seq.commit(staged).unwrap();
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut carol], &mut blobs);
    bob.drain(&blobs);
    let events = carol.drain(&blobs);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, GroupEvent::Invited { held } if held.group == group)),
        "a Welcome: {events:?}"
    );
    carol.groups.accept_welcome(&group).unwrap();
    assert_eq!(carol.groups.get(&group).unwrap().state, GroupState::Active);
    assert_eq!(carol.groups.get(&group).unwrap().name, "far");
    let out = carol
        .groups
        .send(&group, text("back"), None, now_ms())
        .unwrap();
    deliver(out, &mut [&mut alice, &mut bob], &mut blobs);
    assert!(matches!(
        alice.drain(&blobs).as_slice(),
        [GroupEvent::Message { .. }]
    ));
}

#[test]
fn a_large_group_parks_its_welcome_in_the_blob_store() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let mut alice = Party::new();
    let created = alice.groups.create("crowd", now_ms()).unwrap();
    seq.create(created);
    let group = created.group;
    let mut others: Vec<Party> = (0..20).map(|_| Party::new()).collect();
    let packages: Vec<Vec<u8>> = others
        .iter_mut()
        .map(|p| {
            let kp = p.key_package();
            alice
                .groups
                .verify_key_package(&p.id(), &kp, now_ms())
                .unwrap()
        })
        .collect();
    let staged = alice.groups.stage_add(&group, &packages).unwrap();
    seq.commit(staged).unwrap();
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(
        out.uploads.len(),
        1,
        "a Welcome for 21 does not fit an envelope"
    );
    let mut refs: Vec<&mut Party> = others.iter_mut().collect();
    deliver(out, refs.as_mut_slice(), &mut blobs);
    for party in others.iter_mut() {
        let events = party.drain(&blobs);
        let [GroupEvent::Invited { held }] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(held.group, group);
        party.groups.accept_welcome(&group).unwrap();
        assert_eq!(party.groups.get(&group).unwrap().members.len(), 21);
    }
    // And a text still goes inline, to everyone.
    let out = alice
        .groups
        .send(&group, text("hello crowd"), None, now_ms())
        .unwrap();
    assert!(out.uploads.is_empty());
    assert_eq!(out.envelopes.len(), 20);
}

#[test]
fn key_packages_are_kept_up_and_spent_ones_dropped() {
    let mut alice = Party::new();
    let (packages, last) = alice.groups.deposit(now_ms()).unwrap();
    assert_eq!(packages.len(), KEY_PACKAGE_TARGET);
    assert!(last.is_some());
    let refs: Vec<[u8; 32]> = packages.iter().map(|p| p.r#ref).collect();
    assert!(
        alice.groups.apply_status(&refs[..15]).unwrap(),
        "below the minimum"
    );
    assert_eq!(alice.groups.key_packages_on_deposit(), 5);
    let (packages, last2) = alice.groups.deposit(now_ms()).unwrap();
    assert_eq!(packages.len(), KEY_PACKAGE_TARGET);
    assert_eq!(
        last2.unwrap().r#ref,
        last.unwrap().r#ref,
        "not due for rotation"
    );
    // A package from another identity is refused, as is one signed wrong.
    let bob = Party::new();
    let bob_kp = {
        let mut bob = bob;
        bob.key_package()
    };
    assert!(
        alice
            .groups
            .verify_key_package(&alice.id(), &bob_kp, now_ms())
            .is_err()
    );
    assert!(
        alice
            .groups
            .verify_key_package(&alice.id(), b"junk", now_ms())
            .is_err()
    );
}

#[test]
fn state_survives_a_reload_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let store = crate::store::Store::open(dir.path()).unwrap();
    let identity = Arc::new(Identity::generate());
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let group = {
        let mut groups = Groups::load(&store, identity.clone()).unwrap();
        let created = groups.create("kept", now_ms()).unwrap();
        seq.create(created);
        let mut bob = Party::new();
        let kp = groups
            .verify_key_package(&bob.id(), &bob.key_package(), now_ms())
            .unwrap();
        let staged = groups.stage_add(&created.group, &[kp]).unwrap();
        seq.commit(staged).unwrap();
        let out = groups.commit_staged(&created.group, now_ms()).unwrap();
        deliver(out, &mut [&mut bob], &mut blobs);
        let (packages, _) = groups.deposit(now_ms()).unwrap();
        assert_eq!(packages.len(), KEY_PACKAGE_TARGET);
        created.group
    };
    let mut groups = Groups::load(&store, identity).unwrap();
    let record = groups.get(&group).unwrap();
    assert_eq!(record.name, "kept");
    assert_eq!(record.members.len(), 2);
    assert_eq!(groups.key_packages_on_deposit(), KEY_PACKAGE_TARGET);
    // The MLS state is there: a message can be made and a commit staged.
    assert!(
        groups
            .send(&group, text("still here"), None, now_ms())
            .is_ok()
    );
    let staged = groups.stage_self_update(&group).unwrap();
    assert_eq!(staged.epoch, 1);
    assert_eq!(groups.sequencer_entry(&group).unwrap().epoch, 1);
}

/// Alice makes a group and adds bob with both his devices, and carol, in
/// one commit; everyone says yes.
fn with_devices(
    seq: &mut Sequencer,
    blobs: &mut HashMap<String, Vec<Vec<u8>>>,
) -> (Party, Party, Party, Party, GroupId) {
    let mut alice = Party::new();
    let mut bob = Party::new();
    let mut laptop = Party::device_of(&bob, "laptop");
    let mut carol = Party::new();
    let created = alice.groups.create("devices", now_ms()).unwrap();
    seq.create(created);
    let group = created.group;
    let bob_kp = bob.key_package();
    let laptop_kp = laptop.key_package();
    let carol_kp = carol.key_package();
    // The laptop's package names bob and is signed by a key bob certified.
    assert!(
        alice
            .groups
            .verify_key_package(&carol.id(), &laptop_kp, now_ms())
            .is_err(),
        "another identity's"
    );
    let packages = vec![
        alice
            .groups
            .verify_key_package(&bob.id(), &bob_kp, now_ms())
            .unwrap(),
        alice
            .groups
            .verify_key_package(&bob.id(), &laptop_kp, now_ms())
            .unwrap(),
        alice
            .groups
            .verify_key_package(&carol.id(), &carol_kp, now_ms())
            .unwrap(),
    ];
    let staged = alice.groups.stage_add(&group, &packages).unwrap();
    seq.commit(staged).unwrap();
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(out.envelopes.len(), 3, "a Welcome per leaf");
    deliver(out, &mut [&mut bob, &mut laptop, &mut carol], blobs);
    for party in [&mut bob, &mut laptop, &mut carol] {
        let events = party.drain(blobs);
        let [GroupEvent::Invited { held }] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(held.members.len(), 3, "members are identities");
        party.groups.accept_welcome(&group).unwrap();
    }
    (alice, bob, laptop, carol, group)
}

#[test]
fn devices_are_leaves_of_their_identity() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut laptop, mut carol, group) = with_devices(&mut seq, &mut blobs);
    let record = alice.groups.get(&group).unwrap();
    assert_eq!(record.members.len(), 4, "a leaf per device");
    assert_eq!(record.identities(), vec![alice.id(), bob.id(), carol.id()]);
    assert_eq!(record.devices_of(&bob.id()), vec![bob.id(), laptop.id()]);
    assert!(record.is_admin(&alice.id()) && !record.is_admin(&bob.id()));
    for party in [&laptop, &carol] {
        assert_eq!(party.groups.get(&group).unwrap().members.len(), 4);
    }

    // Alice writes: bob reads it on both devices. The laptop writes:
    // everyone, bob's primary included, reads it as bob's.
    let out = alice
        .groups
        .send(&group, text("hello"), None, now_ms())
        .unwrap();
    assert_eq!(out.envelopes.len(), 3);
    deliver(out, &mut [&mut bob, &mut laptop, &mut carol], &mut blobs);
    for party in [&mut bob, &mut laptop, &mut carol] {
        assert!(matches!(
            party.drain(&blobs).as_slice(),
            [GroupEvent::Message { from, .. }] if *from == alice.id()
        ));
    }
    let out = laptop
        .groups
        .send(&group, text("from the laptop"), None, now_ms())
        .unwrap();
    assert_eq!(out.envelopes.len(), 3, "to alice, carol and bob's primary");
    deliver(out, &mut [&mut alice, &mut bob, &mut carol], &mut blobs);
    let bob_id = bob.id();
    for party in [&mut alice, &mut bob, &mut carol] {
        assert!(matches!(
            party.drain(&blobs).as_slice(),
            [GroupEvent::Message { from, content, .. }]
                if *from == bob_id && *content == text("from the laptop")
        ));
    }

    // Bob, no admin, adds a device of his own: allowed, and no change to
    // the members as identities. Carol may not add bob's device.
    let mut phone = Party::device_of(&bob, "phone");
    let phone_kp = phone.key_package();
    let verified = bob
        .groups
        .verify_key_package(&bob.id(), &phone_kp, now_ms())
        .unwrap();
    assert!(matches!(
        carol
            .groups
            .stage_add(&group, std::slice::from_ref(&verified)),
        Err(GroupError::NotAdmin)
    ));
    let staged = bob.groups.stage_add(&group, &[verified]).unwrap();
    seq.commit(staged).unwrap();
    let out = bob.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(
        out.envelopes.len(),
        4,
        "the commit to three leaves, the Welcome to one"
    );
    // The phone was told of the group when it was linked: the Welcome
    // from its own identity is taken without asking, alias and all.
    phone
        .groups
        .expect_groups([(
            group,
            ExpectedGroup {
                name: "devices".into(),
                alias: Some("work".into()),
            },
        )])
        .unwrap();
    deliver(
        out,
        &mut [&mut alice, &mut laptop, &mut carol, &mut phone],
        &mut blobs,
    );
    for party in [&mut alice, &mut laptop, &mut carol] {
        assert_eq!(
            party.drain(&blobs),
            vec![GroupEvent::Changed {
                group,
                by: bob.id(),
                change: Change::Updated,
            }]
        );
        assert_eq!(party.groups.get(&group).unwrap().members.len(), 5);
        assert_eq!(party.groups.get(&group).unwrap().identities().len(), 3);
    }
    assert_eq!(phone.drain(&blobs), vec![GroupEvent::Joined { group }]);
    let record = phone.groups.get(&group).unwrap();
    assert_eq!(record.state, GroupState::Active);
    assert_eq!(record.alias.as_deref(), Some("work"));
    assert_eq!(record.devices_of(&bob.id()).len(), 3);
    assert!(phone.groups.expected(&group).is_none());
    let out = phone
        .groups
        .send(&group, text("phone here"), None, now_ms())
        .unwrap();
    assert_eq!(out.envelopes.len(), 4);
    deliver(
        out,
        &mut [&mut alice, &mut bob, &mut laptop, &mut carol],
        &mut blobs,
    );
    assert!(matches!(
        alice.drain(&blobs).as_slice(),
        [GroupEvent::Message { from, .. }] if *from == bob_id
    ));
    bob.drain(&blobs);
    laptop.drain(&blobs);
    carol.drain(&blobs);

    // A forged device leaf, its certificate not bob's word, is refused.
    let mallory = Party::new();
    let forged = {
        let identity = Arc::new(Identity::generate());
        let mut certificate = mallory
            .identity
            .certify_device(&identity.user_id(), "x", now_ms())
            .unwrap();
        certificate.account = bob.id();
        let mut party = Party {
            identity: identity.clone(),
            groups: Groups::ephemeral_device(identity, certificate),
            inbox: Vec::new(),
        };
        party.key_package()
    };
    assert!(
        alice
            .groups
            .verify_key_package(&bob.id(), &forged, now_ms())
            .is_err()
    );

    // Bob takes the phone out again (unlinked, say): the identity stays.
    // Carol may not touch bob's devices; alice removes bob whole.
    assert!(matches!(
        carol.groups.stage_remove_device(&group, &laptop.id()),
        Err(GroupError::NotAdmin)
    ));
    assert!(bob.groups.stage_remove_device(&group, &bob.id()).is_err());
    let staged = bob.groups.stage_remove_device(&group, &phone.id()).unwrap();
    seq.commit(staged).unwrap();
    let out = bob.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(
        out,
        &mut [&mut alice, &mut laptop, &mut carol, &mut phone],
        &mut blobs,
    );
    assert_eq!(
        alice.drain(&blobs),
        vec![GroupEvent::Changed {
            group,
            by: bob.id(),
            change: Change::Updated,
        }]
    );
    laptop.drain(&blobs);
    carol.drain(&blobs);
    assert_eq!(
        phone.drain(&blobs),
        vec![GroupEvent::Removed {
            group,
            by: bob.id()
        }]
    );
    assert_eq!(alice.groups.get(&group).unwrap().identities().len(), 3);
    let staged = alice.groups.stage_remove(&group, &[bob.id()]).unwrap();
    seq.commit(staged).unwrap();
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    assert_eq!(out.envelopes.len(), 3);
    deliver(out, &mut [&mut bob, &mut laptop, &mut carol], &mut blobs);
    for party in [&mut bob, &mut laptop] {
        assert_eq!(
            party.drain(&blobs),
            vec![GroupEvent::Removed {
                group,
                by: alice.id()
            }]
        );
    }
    assert_eq!(
        carol.drain(&blobs),
        vec![GroupEvent::Changed {
            group,
            by: alice.id(),
            change: Change::Removed(vec![bob.id()]),
        }]
    );
    assert_eq!(
        carol.groups.get(&group).unwrap().identities(),
        vec![alice.id(), carol.id()]
    );
}

#[test]
fn a_device_out_of_sync_is_re_added_by_its_identitys_other_device() {
    let mut seq = Sequencer::default();
    let mut blobs = HashMap::new();
    let (mut alice, mut bob, mut laptop, mut carol, group) = with_devices(&mut seq, &mut blobs);
    // The laptop misses many commits.
    for i in 0..(HOLD_LIMIT + 1) {
        let staged = alice.groups.stage_rename(&group, &format!("n{i}")).unwrap();
        seq.commit(staged).unwrap();
        let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
        deliver(
            Outgoing {
                id: None,
                envelopes: out
                    .envelopes
                    .into_iter()
                    .filter(|e| e.to != laptop.id())
                    .collect(),
                uploads: Vec::new(),
            },
            &mut [&mut bob, &mut carol],
            &mut blobs,
        );
        bob.drain(&blobs);
        carol.drain(&blobs);
    }
    let staged = alice.groups.stage_rename(&group, "far").unwrap();
    seq.commit(staged).unwrap();
    let out = alice.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut bob, &mut laptop, &mut carol], &mut blobs);
    bob.drain(&blobs);
    carol.drain(&blobs);
    assert_eq!(laptop.drain(&blobs), vec![GroupEvent::OutOfSync { group }]);
    // The request goes to the admin and to bob's primary; bob, no admin,
    // answers for his own device.
    let out = laptop.groups.rejoin_request(&group, now_ms()).unwrap();
    assert_eq!(out.envelopes.len(), 2);
    deliver(out, &mut [&mut alice, &mut bob], &mut blobs);
    assert!(matches!(
        alice.drain(&blobs).as_slice(),
        [GroupEvent::RejoinRequest { member, .. }] if *member == bob.id()
    ));
    let events = bob.drain(&blobs);
    let [
        GroupEvent::RejoinRequest {
            member,
            key_package,
            ..
        },
    ] = events.as_slice()
    else {
        panic!("{events:?}");
    };
    assert_eq!(*member, bob.id());
    assert!(matches!(
        carol.groups.stage_rejoin(&group, bob.id(), key_package),
        Err(GroupError::NotAdmin)
    ));
    let staged = bob
        .groups
        .stage_rejoin(&group, bob.id(), key_package)
        .unwrap();
    seq.commit(staged).unwrap();
    let out = bob.groups.commit_staged(&group, now_ms()).unwrap();
    deliver(out, &mut [&mut alice, &mut laptop, &mut carol], &mut blobs);
    assert_eq!(
        alice.drain(&blobs),
        vec![GroupEvent::Changed {
            group,
            by: bob.id(),
            change: Change::Updated,
        }]
    );
    carol.drain(&blobs);
    let events = laptop.drain(&blobs);
    assert!(
        events.contains(&GroupEvent::Joined { group }),
        "a Welcome from its own identity, taken without asking: {events:?}"
    );
    let record = laptop.groups.get(&group).unwrap();
    assert_eq!(record.state, GroupState::Active);
    assert_eq!(record.name, "far");
    assert_eq!(record.identities().len(), 3);
    let out = laptop
        .groups
        .send(&group, text("back"), None, now_ms())
        .unwrap();
    assert_eq!(out.envelopes.len(), 3);
    deliver(out, &mut [&mut alice, &mut bob, &mut carol], &mut blobs);
    let bob_id = bob.id();
    for party in [&mut alice, &mut bob, &mut carol] {
        assert!(matches!(
            party.drain(&blobs).as_slice(),
            [GroupEvent::Message { from, .. }] if *from == bob_id
        ));
    }
}

#[test]
fn groups_named_at_link_time_are_kept_until_their_welcome() {
    let dir = tempfile::tempdir().unwrap();
    let store = crate::store::Store::open(dir.path()).unwrap();
    let identity = Arc::new(Identity::generate());
    let mut groups = Groups::load(&store, identity.clone()).unwrap();
    assert!(!store.has_groups().unwrap());
    let known = groups.create("mine", now_ms()).unwrap().group;
    let team = GroupId::generate();
    let other = GroupId::generate();
    groups
        .expect_groups([
            (
                team,
                ExpectedGroup {
                    name: "team".into(),
                    alias: Some("work".into()),
                },
            ),
            (
                other,
                ExpectedGroup {
                    name: "other".into(),
                    alias: Some("  ".into()),
                },
            ),
            // A group already here keeps what it has.
            (
                known,
                ExpectedGroup {
                    name: "renamed".into(),
                    alias: None,
                },
            ),
        ])
        .unwrap();
    let again = Groups::load(&store, identity).unwrap();
    assert_eq!(
        again.expected(&team),
        Some(&ExpectedGroup {
            name: "team".into(),
            alias: Some("work".into())
        })
    );
    assert_eq!(again.expected(&other).unwrap().alias, None);
    assert!(again.expected(&known).is_none());
    assert_eq!(again.get(&known).unwrap().name, "mine");
    assert_eq!(again.expected_groups().count(), 2);
    assert!(store.has_groups().unwrap());
}
