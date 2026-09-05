//! Property tests: what must hold for every input, not only the ones the
//! unit tests happen to pick. Each property is stated once and checked
//! against hundreds of generated cases; a failing case is minimised and
//! recorded in `properties.proptest-regressions`, which is then replayed
//! first on every run.

use proptest::prelude::*;

use silver_protocol::blob::{BlobKey, CHUNK_BYTES, open_chunk, seal_chunk};
use silver_protocol::envelope::{
    Body, Content, MAX_BODY_BYTES, PAD_BLOCK, ReceiptKind, Sequence, capability, open_bytes,
    seal_bytes, seal_bytes_unsigned,
};
use silver_protocol::identity::IdentitySecrets;
use silver_protocol::prekey::{PrekeySecret, Prekeys};
use silver_protocol::session::Session;
use silver_protocol::transparency::{EntryKind, LogEntry, LogHead, replay, subject};
use silver_protocol::{Identity, KeyBundle, LogPosition, PqPrekeySecret, ProtocolError, UserId};

// ---------------------------------------------------------------------------
// Generators

fn identity(seed: u8) -> Identity {
    Identity::from_secrets(&IdentitySecrets {
        signing_seed: [seed; 32],
        dh_secret: [seed.wrapping_add(100); 32],
    })
}

/// Text of any characters, up to `max` of them.
fn text(max: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..=max).prop_map(String::from_iter)
}

fn bytes(range: std::ops::Range<usize>) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), range)
}

fn hash() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn caps() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop::sample::select(vec![
            capability::RECEIPTS,
            capability::FILES,
            capability::PADDED_FILES,
            capability::LIFECYCLE,
        ]),
        0..=4,
    )
    .prop_map(|caps| caps.into_iter().map(str::to_owned).collect())
}

fn head() -> impl Strategy<Value = Option<LogHead>> {
    prop::option::of((any::<u64>(), hash()).prop_map(|(index, hash)| LogHead { index, hash }))
}

fn content() -> impl Strategy<Value = Content> {
    let alice = identity(1);
    let bob = identity(2);
    prop_oneof![
        text(300).prop_map(|body| Content::Text { body }),
        (prop::bool::ANY, prop::collection::vec(text(40), 0..8)).prop_map(|(read, ids)| {
            Content::Receipt {
                kind: if read {
                    ReceiptKind::Read
                } else {
                    ReceiptKind::Delivered
                },
                ids,
            }
        }),
        (text(100), any::<u64>(), hash(), any::<u32>()).prop_map(
            move |(name, size, sha256, chunks)| Content::File {
                name,
                size,
                blob: "00112233445566778899aabbccddeeff".into(),
                key: BlobKey::from_parts(sha256, [7u8; 24]),
                chunks,
                sha256,
            }
        ),
        any::<u64>().prop_map(move |at| Content::Revocation(alice.revocation(at))),
        any::<u64>().prop_map(move |at| Content::Succession(identity(1).succeed_to(&bob, at))),
    ]
}

fn kind() -> impl Strategy<Value = EntryKind> {
    prop_oneof![
        Just(EntryKind::Bundle),
        Just(EntryKind::Revocation),
        Just(EntryKind::Succession),
    ]
}

/// Damage one bit of `bytes` at a position chosen by `at`.
fn flip(bytes: &mut [u8], at: usize) {
    let i = at % bytes.len();
    bytes[i] ^= 1 << (at % 8);
}

fn plain_body(content: Content, caps: &[String], head: Option<LogHead>) -> Vec<u8> {
    let caps: Vec<&str> = caps.iter().map(String::as_str).collect();
    Body::plain_with_caps_and_head(content, 1, Sequence { epoch: 2, seq: 3 }, &caps, head)
        .encode()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Bodies

proptest! {
    /// Any content encodes to a multiple of the padding block and decodes
    /// back to itself, or is refused as too large; nothing in between.
    #[test]
    fn body_round_trips_or_is_too_large(
        content in content(),
        sent_at_ms in any::<u64>(),
        epoch in any::<u64>(),
        seq in any::<u64>(),
        caps in caps(),
        head in head(),
    ) {
        let cap_refs: Vec<&str> = caps.iter().map(String::as_str).collect();
        let body = Body::plain_with_caps_and_head(
            content.clone(),
            sent_at_ms,
            Sequence { epoch, seq },
            &cap_refs,
            head,
        );
        match body.encode() {
            Ok(encoded) => {
                prop_assert_eq!(encoded.len() % PAD_BLOCK, 0);
                prop_assert!(!encoded.is_empty() && encoded.len() <= MAX_BODY_BYTES);
                match Body::decode(&encoded).unwrap() {
                    Body::Plain {
                        sent_at_ms: t,
                        sequence,
                        content: c,
                        caps: cs,
                        head: h,
                    } => {
                        prop_assert_eq!((t, sequence.epoch, sequence.seq), (sent_at_ms, epoch, seq));
                        prop_assert_eq!(c, content);
                        prop_assert_eq!(cs, caps);
                        prop_assert_eq!(h, head);
                    }
                    Body::Ratchet(_) => prop_assert!(false, "a plain body decoded as a ratchet body"),
                }
            }
            Err(ProtocolError::TooLarge(n)) => prop_assert!(n > MAX_BODY_BYTES),
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }

    /// A text of any length up to well past the limit either encodes within
    /// the limit or is refused, and a refusal happens only within one
    /// padding block plus the JSON framing of the limit, never earlier.
    #[test]
    fn body_size_limit_is_exact(len in 0usize..40_000) {
        // The bytes around the text in the encoding, an upper bound.
        const FRAMING: usize = 100;
        let body = Body::plain(Content::Text { body: "x".repeat(len) }, 0, Sequence::default());
        match body.encode() {
            Ok(encoded) => {
                prop_assert!(encoded.len() <= MAX_BODY_BYTES);
                prop_assert!(len < MAX_BODY_BYTES);
            }
            Err(ProtocolError::TooLarge(n)) => {
                prop_assert!(n > MAX_BODY_BYTES);
                prop_assert_eq!(n % PAD_BLOCK, 0);
                prop_assert!(len + FRAMING + PAD_BLOCK > MAX_BODY_BYTES);
            }
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The sealed layer

proptest! {
    /// A sealed envelope opens for its recipient and for nobody else, and
    /// any damage to any field is refused.
    #[test]
    fn envelope_opens_only_intact_and_only_for_the_recipient(
        content in content(),
        caps in caps(),
        head in head(),
        signed in prop::bool::ANY,
        at in any::<usize>(),
        field in 0u8..4,
    ) {
        let alice = identity(1);
        let bob = identity(2);
        let carol = identity(3);
        let body = plain_body(content, &caps, head);
        let bundle = bob.key_bundle();
        // A deniable body must say v4, and a signed one must not.
        let body = if signed { body } else { b"{\"v\":4}".to_vec() };
        let envelope = if signed {
            seal_bytes(&alice, &bundle, &body).unwrap()
        } else {
            seal_bytes_unsigned(&alice, &bundle, &body).unwrap()
        };

        let opened = open_bytes(&bob, &envelope).unwrap();
        prop_assert_eq!(opened.from, alice.user_id());
        prop_assert_eq!(opened.signed, signed);
        prop_assert_eq!(&*opened.body, &body[..]);
        prop_assert!(open_bytes(&carol, &envelope).is_err());

        let mut damaged = envelope.clone();
        match field {
            0 => flip(&mut damaged.ciphertext, at),
            1 => flip(&mut damaged.nonce, at),
            2 => flip(&mut damaged.ephemeral_public.0, at),
            _ => damaged.to = carol.user_id(),
        }
        prop_assert!(open_bytes(&bob, &damaged).is_err());
        prop_assert!(open_bytes(&carol, &damaged).is_err());
    }

    /// The sender's signature at the sealed layer cannot be moved to a
    /// different body: a signed body re-sealed by someone else is refused
    /// under the original sender's name.
    #[test]
    fn a_signed_body_cannot_be_resealed_by_another(content in content()) {
        let alice = identity(1);
        let bob = identity(2);
        let mallory = identity(4);
        let body = plain_body(content, &[], None);
        // Mallory seals Alice's body under her own key: it opens as from
        // Mallory, never as from Alice.
        let envelope = seal_bytes(&mallory, &bob.key_bundle(), &body).unwrap();
        prop_assert_eq!(open_bytes(&bob, &envelope).unwrap().from, mallory.user_id());
        let _ = alice;
    }
}

// ---------------------------------------------------------------------------
// Sessions

#[derive(Clone, Copy, Debug)]
enum Side {
    Alice,
    Bob,
}

#[derive(Clone, Debug)]
enum Op {
    /// A side sends a message of this many bytes.
    Send(Side, usize),
    /// The other side receives one of the messages in flight, chosen by
    /// index modulo how many there are, so delivery is reordered.
    Deliver(Side, usize),
}

fn schedule() -> impl Strategy<Value = Vec<Op>> {
    let side = prop::bool::ANY.prop_map(|a| if a { Side::Alice } else { Side::Bob });
    prop::collection::vec(
        prop_oneof![
            (side.clone(), 0usize..200).prop_map(|(s, n)| Op::Send(s, n)),
            (side, any::<usize>()).prop_map(|(s, i)| Op::Deliver(s, i)),
        ],
        1..40,
    )
}

/// Bob's bundle: classical prekeys, and ML-KEM keys plus the capability
/// when `pq` is set.
fn bob_bundle(bob: &Identity, pq: bool) -> (KeyBundle, PrekeySecret, Option<PqPrekeySecret>) {
    let signed = PrekeySecret::from_bytes(1, [9u8; 32], 0);
    let pq_secret = pq.then(|| PqPrekeySecret::from_seed(2, [11u8; 64], 0));
    let mut prekeys = Prekeys::classical(signed.signed_by(bob), Vec::new());
    prekeys.pq_signed = pq_secret.as_ref().map(|k| k.signed_by(bob));
    let mut bundle = bob.key_bundle_with(prekeys);
    if pq {
        bundle = bundle.with_caps(
            bob,
            vec![silver_protocol::bundle::capability::PQ_RATCHET.to_owned()],
        );
    }
    (bundle, signed, pq_secret)
}

fn handshake(pq: bool) -> (Session, Session) {
    let alice = identity(1);
    let bob = identity(2);
    let (bundle, signed, pq_secret) = bob_bundle(&bob, pq);
    let (a, init) = Session::initiate(&alice, &bundle).unwrap();
    let b = Session::respond(
        &bob,
        &alice.user_id(),
        &signed,
        None,
        pq_secret.as_ref(),
        &init,
        pq,
    )
    .unwrap();
    assert_eq!(a.is_pq_ratchet(), pq);
    (a, b)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Under any schedule of sends and reordered deliveries, every message
    /// that arrives decrypts to what was sent, a damaged copy is refused
    /// without disturbing the session, and a message is read once.
    #[test]
    fn sessions_survive_any_schedule(ops in schedule(), pq in prop::bool::ANY, at in any::<usize>()) {
        let (mut a, mut b) = handshake(pq);
        // Messages in flight from each side: (plaintext, message).
        let mut from_a = Vec::new();
        let mut from_b = Vec::new();
        let mut counter = 0u32;
        let mut delivered = 0;
        for op in ops {
            match op {
                Op::Send(Side::Alice, n) => {
                    let plaintext = vec![counter as u8; n];
                    counter += 1;
                    from_a.push((plaintext.clone(), a.encrypt(&plaintext).unwrap()));
                }
                Op::Send(Side::Bob, n) => {
                    // A responder cannot send before it has received.
                    if !b.can_send() {
                        continue;
                    }
                    let plaintext = vec![counter as u8; n];
                    counter += 1;
                    from_b.push((plaintext.clone(), b.encrypt(&plaintext).unwrap()));
                }
                Op::Deliver(side, i) => {
                    let (queue, receiver) = match side {
                        Side::Alice => (&mut from_b, &mut a),
                        Side::Bob => (&mut from_a, &mut b),
                    };
                    if queue.is_empty() {
                        continue;
                    }
                    let (plaintext, message) = queue.remove(i % queue.len());
                    // Damage first: refused, and the session still reads the
                    // real message afterwards.
                    let mut damaged = message.clone();
                    if damaged.ciphertext.is_empty() {
                        damaged.header.n ^= 1;
                    } else {
                        flip(&mut damaged.ciphertext, at.wrapping_add(delivered));
                    }
                    prop_assert!(receiver.decrypt(&damaged).is_err());
                    prop_assert_eq!(&*receiver.decrypt(&message).unwrap(), &plaintext[..]);
                    // Replayed: refused (the key is gone).
                    prop_assert!(receiver.decrypt(&message).is_err());
                    delivered += 1;
                }
            }
        }
        // Whatever is still in flight arrives in the end.
        for (plaintext, message) in from_a {
            prop_assert_eq!(&*b.decrypt(&message).unwrap(), &plaintext[..]);
        }
        for (plaintext, message) in from_b {
            prop_assert_eq!(&*a.decrypt(&message).unwrap(), &plaintext[..]);
        }
    }
}

// ---------------------------------------------------------------------------
// Statements and signatures

proptest! {
    /// Every signature checks under its own domain and message and under
    /// no other.
    #[test]
    fn signatures_bind_domain_and_message(
        domain in bytes(0..40),
        message in bytes(0..200),
        at in any::<usize>(),
        which in prop::bool::ANY,
    ) {
        let alice = identity(1);
        let sig = alice.sign(&domain, &message);
        prop_assert!(alice.user_id().verify(&domain, &message, &sig).is_ok());
        prop_assert!(identity(2).user_id().verify(&domain, &message, &sig).is_err());
        let mut other_domain = domain.clone();
        let mut other_message = message.clone();
        if which && !domain.is_empty() {
            flip(&mut other_domain, at);
        } else if !message.is_empty() {
            flip(&mut other_message, at);
        } else {
            other_message.push(0);
        }
        prop_assert!(alice.user_id().verify(&other_domain, &other_message, &sig).is_err());
        let mut damaged = sig;
        flip(&mut damaged, at);
        prop_assert!(alice.user_id().verify(&domain, &message, &damaged).is_err());
    }

    /// A revocation or succession with any field changed does not verify.
    #[test]
    fn lifecycle_statements_reject_any_change(
        at_ms in any::<u64>(),
        delta in 1u64..1000,
        field in 0u8..5,
        at in any::<usize>(),
    ) {
        let alice = identity(1);
        let bob = identity(2);
        let carol = identity(3);

        let rev = alice.revocation(at_ms);
        prop_assert!(rev.verify().is_ok());
        let mut changed = rev.clone();
        match field {
            0 => changed.identity = carol.user_id(),
            1 => changed.created_at_ms = at_ms.wrapping_add(delta),
            _ => flip(&mut changed.signature, at),
        }
        prop_assert!(changed.verify().is_err());

        let succ = alice.succeed_to(&bob, at_ms);
        prop_assert!(succ.verify().is_ok());
        let mut changed = succ.clone();
        match field {
            0 => changed.old = carol.user_id(),
            1 => changed.new = carol.user_id(),
            2 => changed.created_at_ms = at_ms.wrapping_add(delta),
            3 => flip(&mut changed.old_signature, at),
            _ => flip(&mut changed.new_signature, at),
        }
        prop_assert!(changed.verify().is_err());
    }
}

// ---------------------------------------------------------------------------
// The transparency log

proptest! {
    /// A chain replays to its head, and any change to any entry breaks
    /// the replay and moves the head.
    #[test]
    fn a_changed_entry_breaks_the_chain(
        entries in prop::collection::vec((hash(), kind(), hash(), any::<u64>()), 1..12),
        which in any::<usize>(),
        field in 0u8..6,
        at in any::<usize>(),
    ) {
        let mut head = LogHead::EMPTY;
        let mut chain = Vec::new();
        for (subject, kind, leaf, at_ms) in &entries {
            let entry = LogEntry::after(&head, *subject, *kind, *leaf, *at_ms);
            head = entry.head();
            chain.push(entry);
        }
        prop_assert_eq!(replay(&LogHead::EMPTY, &chain, Some(&head)).unwrap(), head);
        prop_assert_eq!(replay(&LogHead::EMPTY, &chain, None).unwrap(), head);
        // From any point in the middle too.
        let mid = which % chain.len();
        let from = if mid == 0 { LogHead::EMPTY } else { chain[mid - 1].head() };
        prop_assert_eq!(replay(&from, &chain[mid..], Some(&head)).unwrap(), head);

        let mut changed = chain.clone();
        let index = which % chain.len();
        let entry = &mut changed[index];
        match field {
            0 => entry.index = entry.index.wrapping_add(1),
            1 => flip(&mut entry.prev, at),
            2 => flip(&mut entry.subject, at),
            3 => {
                entry.kind = match entry.kind {
                    EntryKind::Bundle => EntryKind::Revocation,
                    EntryKind::Revocation => EntryKind::Succession,
                    EntryKind::Succession => EntryKind::Bundle,
                }
            }
            4 => flip(&mut entry.leaf, at),
            _ => entry.at_ms = entry.at_ms.wrapping_add(1),
        }
        prop_assert!(replay(&LogHead::EMPTY, &changed, Some(&head)).is_err());
        prop_assert_ne!(changed[index].head(), chain[index].head());
        // Dropping an entry from the middle breaks it as well; dropping the
        // last one is a shorter page, which replays to the head before.
        let mut shorter = chain.clone();
        let dropped = which % chain.len();
        shorter.remove(dropped);
        if dropped + 1 == chain.len() {
            let before = if dropped == 0 { LogHead::EMPTY } else { chain[dropped - 1].head() };
            prop_assert_eq!(replay(&LogHead::EMPTY, &shorter, Some(&head)).unwrap(), before);
        } else {
            prop_assert!(replay(&LogHead::EMPTY, &shorter, Some(&head)).is_err());
        }
    }

    /// The leaf of a bundle does not depend on its one-time keys, and does
    /// depend on everything else.
    #[test]
    fn bundle_leaf_ignores_one_time_keys_only(
        one_time in 0usize..5,
        pq_one_time in 0usize..3,
        pq in prop::bool::ANY,
        field in 0u8..4,
        at in any::<usize>(),
    ) {
        let bob = identity(2);
        let (mut bundle, _, _) = bob_bundle(&bob, pq);
        let prekeys = bundle.prekeys.as_mut().unwrap();
        prekeys.one_time = (0..one_time)
            .map(|i| PrekeySecret::from_bytes(10 + i as u32, [i as u8 + 1; 32], 0).one_time())
            .collect();
        prekeys.pq_one_time = (0..pq_one_time)
            .map(|i| PqPrekeySecret::from_seed(20 + i as u32, [i as u8 + 1; 64], 0).signed_by(&bob))
            .collect();
        let leaf = bundle.transparency_leaf();
        let mut stripped = bundle.clone();
        let prekeys = stripped.prekeys.as_mut().unwrap();
        prekeys.one_time.clear();
        prekeys.pq_one_time.clear();
        prop_assert_eq!(stripped.transparency_leaf(), leaf);
        prop_assert_eq!(bundle.without_prekeys().transparency_leaf() == leaf, false);

        let mut changed = bundle.clone();
        match field {
            0 => flip(&mut changed.signature, at),
            1 => changed.prekeys.as_mut().unwrap().signed.id ^= 1,
            2 => changed.caps.push("x".into()),
            _ => changed.dh_public = identity(3).dh_public(),
        }
        prop_assert_ne!(changed.transparency_leaf(), leaf);
        let _ = LogPosition::default();
    }

    /// Subjects of different ids differ.
    #[test]
    fn subjects_are_distinct(a in 0u8..255, b in 0u8..255) {
        let (a, b): (UserId, UserId) = (identity(a).user_id(), identity(b).user_id());
        prop_assert_eq!(subject(&a) == subject(&b), a == b);
    }
}

// ---------------------------------------------------------------------------
// File chunks

proptest! {
    /// A chunk of any size up to the limit round-trips in its place and
    /// nowhere else.
    #[test]
    fn chunks_are_bound_to_their_place(
        plaintext in bytes(0..CHUNK_BYTES + 1),
        index in any::<u32>(),
        total in any::<u32>(),
        key in hash(),
        nonce in any::<[u8; 24]>(),
        at in any::<usize>(),
        field in 0u8..4,
    ) {
        let key = BlobKey::from_parts(key, nonce);
        let blob = "00112233445566778899aabbccddeeff";
        let sealed = seal_chunk(&key, blob, index, total, &plaintext).unwrap();
        prop_assert_eq!(open_chunk(&key, blob, index, total, &sealed).unwrap(), plaintext);
        match field {
            0 => prop_assert!(open_chunk(&key, blob, index ^ 1, total, &sealed).is_err()),
            1 => prop_assert!(open_chunk(&key, blob, index, total ^ 1, &sealed).is_err()),
            2 => prop_assert!(open_chunk(&key, "ffeeddccbbaa99887766554433221100", index, total, &sealed).is_err()),
            _ => {
                let mut damaged = sealed.clone();
                flip(&mut damaged, at);
                prop_assert!(open_chunk(&key, blob, index, total, &damaged).is_err());
            }
        }
        prop_assert!(seal_chunk(&key, blob, index, total, &vec![0; CHUNK_BYTES + 1]).is_err());
    }
}
